import os
import telebot
import asyncio
import threading

from account_generator import generate_single_account

# Hosting app ke Environment Variable se token uthayega
TOKEN = os.environ.get("BOT_TOKEN", "9078663237:AAFf53oC3mhGNWLh53ScGFk1VW-ondTPBzw")
bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_msg = (
        "👑 **SPYRO COMMAND CENTER** 👑\n\n"
        "Welcome Commander! ⚡\n"
        "Cloud Bot is active and ready to deploy Free Fire accounts.\n\n"
        "📌 **Commands:**\n"
        "• `/gen IND` - Generate India Region Bot 🇮🇳\n"
        "• `/gen BD` - Generate Bangladesh Region Bot 🇧🇩\n"
        "• `/gen PK` - Generate Pakistan Region Bot 🇵🇰"
    )
    bot.reply_to(message, welcome_msg, parse_mode="Markdown")

@bot.message_handler(commands=['gen'])
def handle_generation(message):
    args = message.text.split()
    region = args[1].upper() if len(args) > 1 else "IND"
    
    sent_msg = bot.reply_to(
        message, 
        f"⏳ **[CLOUD SYSTEM]** Initializing secure neural link for region `{region}`... 🚀", 
        parse_mode="Markdown"
    )
    
    def run_async_gen():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        account = loop.run_until_complete(generate_single_account(region=region))
        
        if account:
            success_msg = (
                f"✅ **SPYRO BOT DEPLOYED FROM CLOUD!** ⚡\n\n"
                f"🎮 **Nickname:** `{account['nickname']}`\n"
                f"🆔 **UID:** `{account['account_id']}`\n"
                f"🌐 **Region:** `{account['region']}`\n"
                f"📊 **Level:** `{account['level']}`\n"
                f"🔑 **Auth UID:** `{account['auth_uid']}`\n\n"
                f"🔥 *Status:* Ready to conquer Guild Glory!"
            )
            bot.edit_message_text(success_msg, chat_id=message.chat.id, message_id=sent_msg.message_id, parse_mode="Markdown")
        else:
            error_msg = (
                "❌ **[CLOUD DEPLOYMENT FAILED]**\n\n"
                "Server refused connection or rate limited. "
                "Try again using `/gen IND`!"
            )
            bot.edit_message_text(error_msg, chat_id=message.chat.id, message_id=sent_msg.message_id, parse_mode="Markdown")

    threading.Thread(target=run_async_gen).start()

if __name__ == '__main__':
    print("🤖 SPYRO Cloud Telegram Bot is online and listening...")
    bot.polling(none_stop=True)
