# EmployeeListElement

A Employee List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEmployeeID** | **number** | The unique ID of the Employee. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sEmployeeCode** | **string** | The code of the Employee | [default to undefined]
**sEmployeeInternalcode** | **string** | The internalcode of the Employee | [default to undefined]
**bEmployeeIsactive** | **boolean** | Whether the employee is active or not | [default to undefined]
**dtEmployeeHiredate** | **string** | The hiredate of the Employee | [optional] [default to undefined]
**dtEmployeeLeavedate** | **string** | The leavedate of the Employee | [optional] [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [optional] [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { EmployeeListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EmployeeListElement = {
    pkiEmployeeID,
    fkiDepartmentID,
    sEmployeeCode,
    sEmployeeInternalcode,
    bEmployeeIsactive,
    dtEmployeeHiredate,
    dtEmployeeLeavedate,
    sDepartmentNameX,
    sContactFirstname,
    sContactLastname,
    sPhoneE164,
    sEmailAddress,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    sProvinceNameX,
    sCountryNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
