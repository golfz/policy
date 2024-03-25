# Policy

Advanced policy for golang application.

![](./docs/images.png)

Language:
[English](./README.md) |
[ไทย](./README_th.md)

![](https://img.shields.io/badge/build-passing-brightgreen)
![](https://img.shields.io/badge/coverage-100%25-brightgreen)
![](https://img.shields.io/badge/license-MIT-blue)

# Policy Syntax (version 1)

**ข้อตกลงเบื้องต้น**

- 1 user สามารถมีได้มากกว่า 1 policies

## (1) Policy

- Policy คือ fine-grained access control

### โครงสร้างของ Policy

```json
{
    "Version": 1,
    "PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
    "Statements": []
}
```

**ประกอบด้วย**

- 📄 `Version`
- 📄 `PolicyID`
- 📂 `Statements`

**อธิบาย**

- **`Version`** คือ การบอกว่าต้องตีความตามสเปคเวอร์ชันใด
    - ถ้าใช้สเปคตามเอกสารนี้ Version คือ `1`
- **`PolicyID`** คือ รหัสอ้างอิง Policy นี้
    - ในการพิจารณา ไม่สนใจค่านี้
- **`Statements`** คือ ชุดของข้อกำหนดเรื่องสิทธิ์
    - 1 Policy มีได้หลาย Statements (ไม่จำกัด)

## (2) Statements

- คือ ชุดของข้อกำหนดเรื่องสิทธิ์
- โครงสร้างของ Statement

### โครงสร้างของ Statement

```json
{
    "Effect": "Allow | Deny",
    "Resource": "res:::resource-key",
    "Actions": [],
    "Conditions": {
        "AtLeastOne": {},
        "MustHaveAll": {}
    }
}
```

**อธิบาย**

- 📄 `Effect`
    - บอกว่าจะเป็นการ "อนุญาต" หรือ "ไม่อนุญาต"
    - `Allow` คือ "อนุญาต"
    - `Deny` คือ "ไม่อนุญาต"
- 📄 `Resource`
    - ระบุ Statement นี้ คือข้อกำหนด Resource ใด
    - ในแต่ละ Statement จะระบุได้แค่ 1 Resource
    - Resource ต้องขึ้นต้นด้วย `res:::`
- 📂 `Actions`
    - ระบุ Actions ที่กระทำกับ Resource ที่กำหนด
    - ในแต่ละ Statement สามารถระบุได้หลาย Actions, แต่ต้องเป็น Resource เดียวกัน
    - แต่ละ Action ต้องขึ้นต้นด้วย `act:::`
- 📄 `Conditions`
    - คือ เงื่อนไขของ Statement นี้
    - มี 2 ประเภท คือ
        - `AtLeastOne`
        - `MustHaveAll`

## (3) Conditions

- Conditions ทั้งหมดจะต้องอยู่ภายใต้ Quantifier Conditions เสมอ
- Quantifier Conditions คือ ตัวบอกปริมาณ ที่จะถือว่าเป็นไปตาม Conditions
- Quantifier Conditions มี 2 ประเภท ดังนี้
    - `AtLeastOne` (∃)
    - `MustHaveAll` (∀)

### Quantifier Conditions

- `AtLeastOne`
    - จะเป็นจริง เมื่อ : มีอย่างน้อย 1 เงื่อนไขเป็นจริง
- `MustHaveAll`
    - จะเป็นจริง เมื่อ : ทุกเงื่อนไขเป็นจริง

### รูปแบบการเขียน Conditions

```json
{
    "Conditions": {
        "{Quantifier}": {
            "{ValueRefKey}": {
                "{CompareOperator}": ExpectedValue
            }
        }
    }
}
```

### Value Ref Key

- Value Ref Key คือ วิธีอ้างถึงข้อมูลต่าง ๆ ที่ใช้ในการพิจารณา Condition

**รูปแบบ**

```txt
{type}:::subkey1:subkey2:subkeyN
```

- อธิบาย
    - สามารถมี subkey ได้ โดยใช้ `:` (colon) คั่นแต่ละ level
    - ใช้ lower case (`a-z0-9`) ทั้งหมด
    - เว้นวรรคด้วย Underscore (`_`) เช่น `employee_uuid`
- `{type}` มี 2 ประเภท คือ
    - **Resource Properties**
        - คือ การอ้างถึง Properties ของ Resource
        - ขึ้นต้นด้วย `prop:::`
    - **System**
        - คือ การอ่านข้อมูลจาก System ของ server
        - ขึ้นต้นด้วย `sys:::`

### Compare Operator

- คือ ตัวดำเนินการ ในการเปรียบเทียบ ระหว่าง `{ValueRefKey}` และ `{ExpectedValue}`

#### Type ของข้อมูลที่เปรียบเทียบได้

- (1) Primitive Type
    - `String`
    - `Integer`
    - `Float`
    - `Boolean`
- (2) System Type
    - `Date & Time`
- (3) User Property Type
    - `UserProp`

##### (1) Primitive Type

- {T} คือ Type: String, Integer, Float, Boolean
- มี 2 Operators คือ `{T}Equal` และ `{T}In`

###### `{T}Equal`

- เปรียบเทียบ Type ต้องตรงกัน
- เปรียบเทียบ Value ต้องเท่ากัน
- Operator มีดังนี้
    - **`StringEqual`**
    - **`IntegerEqual`**
    - **`FloatEqual`**
    - **`BooleanEqual`**

ตัวอย่าง

```json
{
    "prop:::employee:organization_uuid": {
        "StringEqual": "501228f3f7f34ef18bc99fb73347f518"
    }
}
```

อธิบาย:
ค่า property `"prop:::employee:organization_uuid"`  ของ Resource จะต้องเป็นประเภทข้อมูล `string`
และมีค่าเป็น `"501228f3f7f34ef18bc99fb73347f518"`

###### `{T}In`

- เปรียบเทียบ Type ต้องตรงกัน
- เปรียบเทียบ Value ต้องอยู่ในค่าใดค่าหนึ่งใน Array ของ `{ExpectedValue}`
- Operator มีดังนี้
    - **`StringIn`**
    - **`IntegerIn`**
    - **`FloatIn

ตัวอย่าง

```json
{
    "prop:::employee:organization_uuid": {
        "StringIn": [
            "501228f3f7f34ef18bc99fb73347f518",
            "d23b9e25b0f0405686f0c104007d1955",
            "e45b9e25b0f0405686f0c104007d1904",
            "c78b9e25b0f0405686f0c104007d1967"
        ]
    }
}
```

อธิบาย:
ค่า property `"prop:::employee:organization_uuid"`  ของ Resource จะต้องเป็นประเภทข้อมูล `string`
และมีค่าอยู่ในค่าใดค่าหนึ่งใน Array นี้

##### (2) System Type

⚠️ ยังไม่ได้ implement

**หมวด: เวลา**

- ต้องใช้ `{ValueRefKey}` เป็น `"sys:::time:now"`
- ค่าที่ใช้ใน `{ExpectedValue}` เป็น format : `RFC3339`
- {T} คือ Type: Time, Date, DateTime
- มี 1 Operators คือ `{T}Range`

Operator มีดังนี้

- `TimeRange`
- `DateRange`
- `DateTimeRange`

###### `TimeRange`

```json
{
    "sys:::time:now": {
        "TimeRange": {
            "From": "15:04:05Z",
            "To": "15:04:05Z"
        }
    }
}
```

###### `DateRange`

```json
{
    "sys:::time:now": {
        "DateRange": {
            "From": "2023-01-01",
            "To": "2023-01-31"
        }
    }
}
```

###### `DateTimeRange`

```json
{
    "sys:::now:time": {
        "DateTimeRange": {
            "From": "2006-01-02T15:04:05Z",
            "To": "2006-01-02T15:04:05Z"
        }
    }
}
```

##### (3) User Property Type

- คือ การเปรียบเทียบ Resource's property กับ User's property

Operator มีดังนี้

- `UserPropEqual`

###### `UserPropEqual`

- `{ValueRefKey}`
    - ต้องเป็น property ของ Resource เสมอ
    - ต้องขึ้นต้นด้วย `prop:::` (เนื่องจากอ้างถึง property ของ resource)
- `{ExpectedValue}`
    - คือ property ของ user
    - ต้องขึ้นต้นด้วย `user:::` เสมอ
- User Property ต้องมี type เป็น string เท่านั้น

ตัวอย่าง

```json
{
    "prop:::employee:organization_uuid": {
        "UserPropEqual": "user:::employee:organization:organization_uuid"
    }
}
```

อธิบาย

- เป็นการเปรียบเทียบ property ของ resource กับ property ของ user ต้องมีค่าเท่ากัน และต้องเป็น type เดียวกัน (string)
- ค่า property `"prop:::employee:organization_uuid"`  ของ Resource จะต้องเป็นประเภทข้อมูล `string` และมีค่าตรงกับ user's
  property `"user:::employee:organization:organization_uuid"` ของ user ที่กำลังใช้งานอยู่

ตัวอย่างการนำไปใช้งาน
จากตัวอย่างนี้ สามารถนำไปใช้เมื่อต้องการให้ user ที่กำลังใช้งาน สามารถดำเนินการ (ทำ Actions) ใด ๆ กับ Resource ที่อยู่ใน
organization

## Rule: กฎการพิจารณา

**ข้อตกลงเบื้องต้น**

- 1 คน มีได้มากกว่า 1 policy

**สมมุติว่ามีข้อมูลดังนี้**

**Policy A**

```json
{
    "Version": 1,
    "PolicyID": "A",
    "Statements": [
        {
            // Statement A-1
        },
        {
            // Statement A-2
        }
    ]
}
```

**Policy B**

```json
{
    "Version": 1,
    "PolicyID": "B",
    "Statements": [
        {
            // Statement B-1
        },
        {
            // Statement B-2
        },
        {
            // Statement B-3
        }
    ]
}
```

**Policy C**

```json
{
    "Version": 1,
    "PolicyID": "C",
    "Statements": [
        {
            // Statement C-1
        },
        {
            // Statement C-2
        },
        {
            // Statement C-3
        }
    ]
}
```

**1. รวม Statement จากทุก Policy เข้าด้วยกัน**
ได้ข้อมูลดังนี้

```json
[
    {
        // Statement A-1
    },
    {
        // Statement A-2
    },
    {
        // Statement B-1
    },
    {
        // Statement B-2
    },
    {
        // Statement B-3
    },
    {
        // Statement C-1
    },
    {
        // Statement C-2
    },
    {
        // Statement C-3
    }
]
```

**2. Filter Statement ให้เหลือเฉพาะที่เงื่อนไขถูกต้อง (matched) เท่านั้น**
สมมุติว่าได้ผลลัพธ์ดังนี้

```json
[
    {
        // Statement A-1
    },
    {
        // Statement B-2
    },
    {
        // Statement C-2
    },
    {
        // Statement C-3
    }
]
```

### Rule: กฎการพิจารณาผลลัพธ์

#### Rule 1

- ถ้าไม่มี Statement ที่ matched เลย (filter แล้วได้ 0 statement)
    - return `Deny`

#### Rule 2

- ถ้ามี Statement ที่มี `Effect` เป็น `Deny` อย่างน้อย 1 statement
    - return `Deny`

#### Rule 3

- ถ้าทุก Statements ที่มี `Effect` เป็น `Allow`
    - return `Allow`

### Rule: กฎการพิจารณาเงื่อนไขของ statement

#### Rule 4

- ถ้า Statement ไม่มี Condition
    - matched

#### Rule 5

- ถ้ามี Condition แต่ไม่มี Quantifier : `AtLeastOne` หรือ `MustHaveAll` อย่างใดอย่างหนึ่ง
    - ให้ Quantifier ที่ไม่มี condition มีผลเป็น `matched`

#### Rule 6

- ถ้ามี Condition ให้ AND ผลลัพธ์ของ `AtLeastOne` และ `MustHaveAll`

| `AtLeastOne`  | `MustHaveAll` | ผลลัพธ์       |   |
|---------------|---------------|---------------|---|
| `matched`     | `matched`     | `matched`     | ⭐ |
| `matched`     | `not matched` | `not matched` |   |
| `not matched` | `matched`     | `not matched` |   |
| `not matched` | `not matched` | `not matched` |   |

หมายเหตุ: `matched` มีค่าเท่ากับ `true`