#!/bin/sh

zip -r $ARTIFACT letsencrypt-aws.py requirements.txt

#if [ "$(ls -A $VENV_DIR/lib/python$PYTHON_VERSION/site-packages)" ]; then
  cd $VENV_DIR/lib/python$PYTHON_VERSION/site-packages && zip -r $ARTIFACT . || true
#fi

#if [ "$(ls -A $VENV_DIR/lib64/python$PYTHON_VERSION/site-packages)" ]; then
  cd $VENV_DIR/lib64/python$PYTHON_VERSION/site-packages && zip -r $ARTIFACT . || true
#fi

#if [ "$(ls -A $VENV_DIR/lib/python$PYTHON_VERSION/dist-packages)" ]; then
  cd $VENV_DIR/lib/python$PYTHON_VERSION/dist-packages && zip -r $ARTIFACT . || true
#fi

#if [ "$(ls -A $VENV_DIR/lib64/python$PYTHON_VERSION/dist-packages)" ]; then
  cd $VENV_DIR/lib64/python$PYTHON_VERSION/dist-packages && zip -r $ARTIFACT . || true
#fi
