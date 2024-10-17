from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Table, Boolean
from sqlalchemy.orm import relationship
from database import Base

friendship = Table('friendship', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('friend_id', Integer, ForeignKey('users.id'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)
    purchases = relationship('Purchase', foreign_keys='Purchase.buyer_id', back_populates='buyer')
    concerned_purchases = relationship('Purchase', foreign_keys='Purchase.concerned_user_id', back_populates='concerned_user')
    friends = relationship('User', 
                           secondary=friendship,
                           primaryjoin=(friendship.c.user_id == id),
                           secondaryjoin=(friendship.c.friend_id == id),
                           backref='befriended_by')
    sent_requests = relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', back_populates='sender')
    received_requests = relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', back_populates='receiver')

class Purchase(Base):
    __tablename__ = 'purchases'
    id = Column(Integer, primary_key=True)
    item = Column(String(100), nullable=False)
    amount = Column(Float, nullable=False)
    date = Column(DateTime, nullable=False)
    buyer_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    concerned_user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    buyer = relationship('User', foreign_keys=[buyer_id], back_populates='purchases')
    concerned_user = relationship('User', foreign_keys=[concerned_user_id], back_populates='concerned_purchases')

class FriendRequest(Base):
    __tablename__ = 'friend_requests'
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    status = Column(String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = Column(DateTime, nullable=False)
    sender = relationship('User', foreign_keys=[sender_id], back_populates='sent_requests')
    receiver = relationship('User', foreign_keys=[receiver_id], back_populates='received_requests')