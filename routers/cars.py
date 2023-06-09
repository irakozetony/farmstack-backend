from typing import Optional, List
from fastapi import APIRouter, Request, Body, status, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from models.models import CarBase, CarDB, CarUpdate
from authentication import AuthHandler

router = APIRouter()
auth_handler = AuthHandler()


@router.get("/", response_description="List all cars")
async def list_cars(
        request: Request,
        min_price: int = 0,
        max_price: int = 100000,
        brand: Optional[str] = None,
        page: int = 1,
        user_id = Depends(auth_handler.auth_wrapper)
) -> List[CarDB]:
    results_per_page = 25
    skip = (page - 1) * results_per_page
    query = {
        "price": {"$lt": max_price, "$gt": min_price}
    }
    if brand:
        query["brand"] = brand
    full_query = request.app.mongodb["Car"].find(query).sort("_id", 1).skip(skip).limit(results_per_page)
    results = [CarDB(**raw_car) async for raw_car in full_query]
    return results


@router.post("/", response_description="Add new car")
async def create_car(request: Request, car: CarBase = Body(...), user_id = Depends(auth_handler.auth_wrapper)):
    car = jsonable_encoder(car)
    car['owner'] = user_id
    new_car = await request.app.mongodb["Car"].insert_one(car)
    created_car = await request.app.mongodb["Car"].find_one({
        "_id": new_car.inserted_id
    })
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_car)


@router.get("/{id}", response_description="Get a single car")
async def show_car(id: str, request: Request):
    car = await request.app.mongodb["Car"].find_one({"_id": id})
    if car is not None:
        return CarDB(**car)
    raise HTTPException(status_code=404, detail=f"Car with id {id} not found")


@router.patch("/{id}", response_description="Update a car")
async def update_car(id: str, request: Request, car: CarUpdate = Body(...), user_id=Depends(auth_handler.auth_wrapper)):
    user = await request.app.mongodb['User'].find_one({'_id': user_id})
    find_car = await request.app.mongodb['Car'].find_one({'_id': id})
    if (find_car['Owner'] != user_id) and user['role'] != 'ADMIN':
        raise HTTPException(status_code=401, detail='Only the owner or an admin can update the car')
    await request.app.mongodb["Car"].update_one(
        {"_id": id}, {"$set": car.dict(exclude_unset=True)}
    )
    car = await request.app.mongodb["Car"].find_one({"_id": id})
    if car is not None:
        return CarDB(**car)
    raise HTTPException(status_code=404, detail=f"Car with id {id} not found")


@router.delete("/{id}", response_description="Delete a car")
async def delete_car(id: str, request: Request):
    delete_result = await request.app.mongodb["Car"].delete_one({"_id": id})
    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

    raise HTTPException(status_code=404, detail=f"Car with id {id} not found")
