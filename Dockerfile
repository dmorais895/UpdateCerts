FROM python:3.8.17-slim-bullseye

LABEL org.opencontainers.image.authors="moraisdavid8@gmail.com"

ARG USERNAME=certs
ARG USER_UID=1000
ARG USER_GID=$USER_UID

WORKDIR /app

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && chown -R ${USERNAME}:${USERNAME} /app \
    && pip install --upgrade setuptools testresources pip requests

USER $USERNAME

COPY --chown=${USERNAME}:${USERNAME} . /app/ 

CMD [ "python", "/app/main.py" ]