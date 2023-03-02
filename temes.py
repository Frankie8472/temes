from __future__ import print_function

import base64
import logging
import os.path
from email.mime.text import MIMEText

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters

debug_log = False

# Global logging
if debug_log:
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']


def load_whitelist_chat():
    file_name = "whitelist_chat"
    whitelist = list()
    file_path = os.path.abspath(os.path.dirname(__file__))
    file_path = os.path.join(file_path, file_name)
    with open(file_path, "r") as f:
        whitelist = f.read().splitlines()
        f.close()
    assert whitelist != list(), "ERROR: No whitelisted emails!"
    return whitelist


def load_whitelist_email():
    file_name = "whitelist_email"
    whitelist = list()
    file_path = os.path.abspath(os.path.dirname(__file__))
    file_path = os.path.join(file_path, file_name)
    with open(file_path, "r") as f:
        whitelist = f.read().splitlines()
        f.close()
    assert whitelist != list(), "ERROR: No whitelisted emails!"
    return whitelist


def load_token(file_name):
    token = None
    file_path = os.path.abspath(os.path.dirname(__file__))
    file_path = os.path.join(file_path, file_name)
    with open(file_path, "r") as f:
        token = f.readline()
        f.close()
    assert token is not None, "ERROR: Token is None"
    return token


def usage_allowed(update: Update):
    whitelist_chat = load_whitelist_chat()
    id = update.effective_chat.id
    ret = False
    if str(id) in whitelist_chat:
        ret = True
    return ret


def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_string().encode("utf-8"))
    body = {'raw': raw_message.decode("utf-8")}
    return body


def send_message(service, user_id, message):
    try:
        message = service.users().messages().send(userId=user_id, body=message).execute()
        # print('Message Id: %s' % message['id'])
        return message
    except Exception as e:
        print('An error occurred: %s' % e)
        return None


async def send_to_gmail(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shows basic usage of the Gmail API.
        Lists the user's Gmail labels.
        """
    global channel

    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    file_path_orig = os.path.abspath(os.path.dirname(__file__))
    file_path_token = os.path.join(file_path_orig, 'token.json')
    if os.path.exists(file_path_token):
        creds = Credentials.from_authorized_user_file(file_path_token, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            file_path_orig = os.path.abspath(os.path.dirname(__file__))
            file_path_cred = os.path.join(file_path_orig, 'credentials.json')
            flow = InstalledAppFlow.from_client_secrets_file(file_path_cred, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(file_path_token, 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        whitelist = load_whitelist_email()
        for email in whitelist:
            msg = f"{update.message.from_user.first_name} {update.message.from_user.last_name} (@{update.message.from_user.username}): \n\n{update.message.text}"
            message_body = create_message('me', email, 'Telegram Message: Sauna Channel', msg)
            send_message(service, 'me', message_body)
    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')
    return


async def pull_email(context: ContextTypes.DEFAULT_TYPE):
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    global channel

    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    file_path_orig = os.path.abspath(os.path.dirname(__file__))
    file_path_token = os.path.join(file_path_orig, 'token.json')
    if os.path.exists(file_path_token):
        creds = Credentials.from_authorized_user_file(file_path_token, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            file_path_orig = os.path.abspath(os.path.dirname(__file__))
            file_path_cred = os.path.join(file_path_orig, 'credentials.json')
            flow = InstalledAppFlow.from_client_secrets_file(file_path_cred, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(file_path_token, 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)

        res = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
        messages = res.get('messages')
        if messages is None:
            return
        for msg in messages:
            txt = service.users().messages().get(userId='me', id=msg['id']).execute()
            service.users().messages().modify(userId='me', id=msg['id'], body={'removeLabelIds': ['UNREAD']}).execute()

            # Get value of 'payload' from dictionary 'txt'
            payload = txt['payload']
            headers = payload['headers']

            # Look for Subject and Sender Email in the headers
            sender = None
            subject = None
            for d in headers:
                if d['name'] == 'Subject':
                    subject = d['value']
                if d['name'] == 'From':
                    sender = d['value']

            assert sender is not None, "ERROR: sender is None"
            assert subject is not None, "ERROR: subject is None"

            service.users().messages().trash(userId='me', id=msg['id']).execute()

            if sender is None:   # TODO: check for empty
                return
            sender = sender[:-1].split("<")[1]
            whitelist = load_whitelist_email()
            if sender in whitelist:
                await context.bot.send_message(chat_id=channel, text=subject)

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global channel
    global run
    if not usage_allowed(update):
        print(">> Killed")
        await context.bot.leave_chat(chat_id=update.effective_chat.id)
        return
    if not run:
        print(">> Started Successfully")
        run = True
        send_to_gmail_handler = MessageHandler(filters.TEXT & (~filters.COMMAND), send_to_gmail)
        application.job_queue.run_repeating(pull_email, interval=5, first=5)
        application.add_handler(send_to_gmail_handler)
        channel = update.effective_chat.id
    return


async def debug(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f">> Channel ID: {update.effective_chat.id}")
    return


if __name__ == '__main__':
    run = False
    channel = None
    test = False

    token = load_token("bot.token")
    application = ApplicationBuilder().token(token=token).build()

    if test:
        # Retrieve Channel ID for whitelist
        debug_handler = CommandHandler('debug', debug)
        application.add_handler(debug_handler)
    else:
        # Relay telegram msg to gmail
        start_handler = CommandHandler('start', start)
        application.add_handler(start_handler)

    # Relay gmail to telegram msg
    application.run_polling()
