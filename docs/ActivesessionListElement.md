# ActivesessionListElement

A Activesession List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiActivesessionID** | **number** | The unique ID of the Activesession | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiComputerID** | **number** | The unique ID of the Computer | [default to undefined]
**fkiCompanyID** | **number** | The unique ID of the Company | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sCompanyNameX** | **string** | The Name of the Company in the language of the requester | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [default to undefined]
**sActivesessionLoginname** | **string** | The loginname of the Activesession | [default to undefined]
**sComputerDescription** | **string** | The description of the Computer | [default to undefined]
**dtActivesessionFirsthit** | **string** | The first hit of the Activesession | [default to undefined]
**dtActivesessionLasthit** | **string** | The last hit of the Activesession | [default to undefined]
**sActivesessionIP** | **string** | Represent an IP address. | [default to undefined]

## Example

```typescript
import { ActivesessionListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ActivesessionListElement = {
    pkiActivesessionID,
    fkiUserID,
    fkiComputerID,
    fkiCompanyID,
    fkiDepartmentID,
    sCompanyNameX,
    sDepartmentNameX,
    sActivesessionLoginname,
    sComputerDescription,
    dtActivesessionFirsthit,
    dtActivesessionLasthit,
    sActivesessionIP,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
