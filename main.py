from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.utils.docker_utils import check_and_update_images

app = FastAPI()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # call and check docker images. Check if there is any updates
    check_and_update_images()
    yield


@app.get("/")
async def root():
    return {"message": "Hello World"}