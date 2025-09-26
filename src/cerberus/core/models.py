from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import json

@dataclass
class PasswordEntry:
    """Represents a single password entry in the password manager."""
    id: str
    website: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    password_strength: Optional[float] = None
    compromised: bool = False
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the password entry to a dictionary for serialization."""
        return {
            'id': self.id,
            'website': self.website,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'tags': self.tags,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'password_strength': self.password_strength,
            'compromised': self.compromised,
            'custom_fields': self.custom_fields
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create a PasswordEntry from a dictionary."""
        return cls(
            id=data.get('id', ''),
            website=data['website'],
            username=data['username'],
            password=data['password'],
            url=data.get('url', ''),
            notes=data.get('notes', ''),
            tags=data.get('tags', []),
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at']),
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
            password_strength=data.get('password_strength'),
            compromised=data.get('compromised', False),
            custom_fields=data.get('custom_fields', {})
        )
