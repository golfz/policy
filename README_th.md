# Policy

Advanced policy for golang application.

![](./docs/images.png)

Language:
[English](./README.md) |
[ไทย](./README_th.md)

![](https://img.shields.io/badge/build-passing-brightgreen)
![](https://img.shields.io/badge/coverage-100%25-brightgreen)
![](https://img.shields.io/badge/license-MIT-blue)

## About

Policy คือ Library สำหรับการตรวจสอบสิทธิ์การเข้าถึงข้อมูล โดยมีการตรวจสอบเงื่อนไขที่เข้มงวด
โดยมีการตรวจสอบเงื่อนไขตามลำดับดังนี้

1. ตรวจสอบว่า User มีสิทธิ์ในการเข้าถึง Resource นั้นหรือไม่
2. ตรวจสอบว่า User มีสิทธิ์ในการเข้าถึง Action นั้นหรือไม่
3. ตรวจสอบว่า User มีสิทธิ์ในการเข้าถึง Resource นั้นโดยเงื่อนไขต่างๆ หรือไม่

## ตัวอย่าง Policy สำหรับ User แต่ละคน

ข้อมูล Policy จะถูกเก็บอยู่ในรูปแบบ JSON ซึ่ง

```json
{
    "Version": 1,
    "PolicyID": "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "res:::employee",
            "Action": [
                "act:::employee:list"
            ]
        },
        {
            "Effect": "Allow",
            "Resource": "res:::employee",
            "Action": [
                "act:::employee:update",
                "act:::employee:delete"
            ],
            "Condition": {
                "AtLeastOne": {
                    "StringEqual": {
                        "prop:::employee:organization_uuid": "601228f3-f7f3-4ef1-8bc9-9fb73347f512"
                    },
                    "StringIn": {
                        "prop:::employee:employee_uuid": [
                            "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
                            "d23b9e25-b0f0-4056-86f0-c104007d1955",
                            "e45b9e25-b0f0-4056-86f0-c104007d1904"
                        ]
                    }
                },
                "MustHaveAll": {
                    "StringEqual": {
                        "prop:::employee:company_uuid": "331228f3-f7f3-4ef1-8bc9-9fb73347f345"
                    },
                    "IntegerIn": {
                        "prop:::employee:level": [
                            1,
                            2,
                            3
                        ]
                    }
                }
            }
        },
        {
            "Effect": "Deny",
            "Resource": "res:::employee",
            "Action": [
                "act:::employee:update",
                "act:::employee:delete"
            ],
            "Condition": {
                "MustHaveAll": {
                    "StringEqual": {
                        "prop:::employee:position": "engineer"
                    }
                }
            }
        },
        {
            "Effect": "Allow",
            "Resource": "res:::report",
            "Action": [
                "act:::report:list",
                "act:::report:read"
            ]
        },
        {
            "Effect": "Allow",
            "Resource": "res:::leave",
            "Action": [
                "act:::leave:approve"
            ],
            "Condition": {
                "AtLeastOne": {
                    "StringIn": {
                        "prop:::employee:employee_uuid": [
                            "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
                            "e45b9e25-b0f0-4056-86f0-c104007d1904",
                            "c78b9e25-b0f0-4056-86f0-c104007d1967",
                            "501228f3-f7f3-4ef1-8bc9-9fb73347f518",
                            "d23b9e25-b0f0-4056-86f0-c104007d1955",
                            "c78b9e25-b0f0-4056-86f0-c104007d1967"
                        ],
                        "prop:::employee:organization_uuid": [
                            "e45b9e25-b0f0-4056-86f0-c104007d1904",
                            "c78b9e25-b0f0-4056-86f0-c104007d1967"
                        ]
                    }
                },
                "MustHaveAll": {
                    "DateRange": {
                        "sys:::now:date": {
                            "From": "2023-01-01+07:00",
                            "to": "2023-07-31+07:00"
                        }
                    }
                }
            }
        }
    ]
}
```