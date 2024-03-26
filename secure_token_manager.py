from typing import Optional
import secrets
from sqlalchemy.orm import Session
from models import Device_Password_Token

class SecureTokenManager:
    def __init__(self, db_session: Session):
        self.db_session = db_session  # SQLAlchemy 数据库会话

    def generate_token(self, device_id: str) -> str:
        """
        为指定的设备 ID 生成一个唯一的令牌，并存储这个映射关系到数据库。
        """
        token = secrets.token_urlsafe(16)  # 使用更安全的令牌
        return token

    def validate_token(self, token: str) -> Optional[str]:
        """
        验证令牌的有效性。如果有效，返回对应的设备 ID。
        """
        device_token = self.db_session.query(Device_Password_Token).filter_by(token=token).first()
        return device_token.id if device_token else None

    def revoke_token(self, token: str):
        """
        撤销令牌，删除其在数据库中的记录。
        """
        device_token = self.db_session.query(Device_Password_Token).filter_by(token=token).first()
        if device_token:
            self.db_session.delete(device_token)
            self.db_session.commit()


# 使用示例
#token_manager = SecureTokenManager()
#device_id = "some_device_id"
# 生成令牌
#token = token_manager.generate_token(device_id)
#print(f"Generated token: {token}")
# 验证令牌
#print(f"Validated device ID: {token_manager.validate_token(token)}")
# 撤销令牌
#token_manager.revoke_token(token)
#print(f"Token revoked: {not token_manager.validate_token(token)}")
