from fastapi import APIRouter, Request, Body, status, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from models.models import UserBase, LoginBase, CurrentUser
from authentication import AuthHandler

router = APIRouter()
auth_handler = AuthHandler()


@router.post("/register", response_description="Register user")
async def register(request: Request, new_user: UserBase = Body(...)):
    new_user.password = auth_handler.get_password_hash(new_user.password)
    new_user = jsonable_encoder(new_user)
    existing_email = await request.app.mongodb['User'].find_one({'email': new_user['email']})
    existing_username = await request.app.mongodb['User'].find_one({'username': new_user['username']})
    if existing_email is not None:
        raise HTTPException(
            status_code=409,
            detail=f"User with email {new_user['email']} already exists"
        )
    if existing_username is not None:
        raise HTTPException(
            status_code=409,
            detail=f"User with username {new_user['username']} already exists"
        )

    user = await request.app.mongodb['User'].insert_one(new_user)
    created_user = await request.app.mongodb['User'].find_one({'_id': user.inserted_id})

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_user)


@router.post("/login", response_description="Login user")
async def login(request: Request, login_user: LoginBase = Body(...)):
    user = await request.app.mongodb['User'].find_one({'email': login_user.email})

    if (user is None) or (not auth_handler.verify_password(login_user.password, user['password'])):
        raise HTTPException(status_code=401, detail='Invalid email and/or password')
    token = auth_handler.encode_token(user['_id'])
    response = JSONResponse(content={'token': token})
    return response


@router.get('/me', response_description='Logged in user data')
async def me(request: Request, user_id=Depends(auth_handler.auth_wrapper)):
    current_user = await request.app.mongodb['User'].find_one({'_id': user_id})
    result = CurrentUser(**current_user).dict()
    result['id'] = user_id
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)
