import logging
import re

import boto3

logger = logging.getLogger()

ecr = boto3.client('ecr')


def is_string(value):
    if type(value) == str:
        return True
    return False


def check_image_uri(image_uri: str):
    logger.info(f"Checking if image {image_uri} exists")
    groups = re.match('([0-9]+)\.dkr\.ecr\.[^\.]+\.amazonaws\.com/([^:]+):(.+)', image_uri).groups()
    registry_id = groups[0]
    repository_name = groups[1]
    image_tag = groups[2]

    response = ecr.describe_images(
        registryId=registry_id,
        repositoryName=repository_name,
        imageIds=[
            {
                'imageTag': image_tag
            }
        ]
    )

    logger.debug(f"Response from ECR: {response}")

    if len(response['imageDetails']) == 1:
        logger.info("Image exists")
        return True
    else:
        logger.info("Image not found")
        raise ValueError(f"Image {image_uri} not found in registry/account {registry_id}")
