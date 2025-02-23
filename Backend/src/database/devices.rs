use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    #[sea_orm(unique)]
    pub mac_address: String,
    pub device_type: i32,
    pub status: i32
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Users,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Status {
    Online = 1,
    Offline = 0,
}

impl From<i32> for Status {
    fn from(value: i32) -> Self {
        match value {
            1 => Status::Online,
            0 => Status::Offline,
            _ => panic!("Invalid value for Status"),
        }
    }
}

impl From<Status> for i32 {
    fn from(status: Status) -> Self {
        match status {
            Status::Online => 1,
            Status::Offline => 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DeviceType {
    Honeypot = 0,
}

impl From<i32> for DeviceType {
    fn from(value: i32) -> Self {
        match value {
            0 => DeviceType::Honeypot,
            _ => panic!("Invalid value for Type"),
        }
    }
}

impl From<DeviceType> for i32 {
    fn from(status: DeviceType) -> Self {
        match status {
            DeviceType::Honeypot => 0,
        }
    }
}