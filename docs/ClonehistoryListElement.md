# ClonehistoryListElement

A Clonehistory List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiClonehistoryID** | **number** | The unique ID of the Clonehistory | [default to undefined]
**fkiUserIDCloning** | **number** | The unique ID of the User | [default to undefined]
**fkiUserIDCloned** | **number** | The unique ID of the User | [default to undefined]
**dtClonehistoryFirsthit** | **string** | The firsthit of the Clonehistory | [default to undefined]
**dtClonehistoryLasthit** | **string** | The lasthit of the Clonehistory | [optional] [default to undefined]
**sUserLoginnameCloning** | **string** | The login name of the User. | [default to undefined]
**sUserFirstnameCloning** | **string** | The first name of the user | [default to undefined]
**sUserLastnameCloning** | **string** | The last name of the user | [default to undefined]
**sUserLoginnameCloned** | **string** | The login name of the User. | [default to undefined]
**sUserFirstnameCloned** | **string** | The first name of the user | [default to undefined]
**sUserLastnameCloned** | **string** | The last name of the user | [default to undefined]

## Example

```typescript
import { ClonehistoryListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ClonehistoryListElement = {
    pkiClonehistoryID,
    fkiUserIDCloning,
    fkiUserIDCloned,
    dtClonehistoryFirsthit,
    dtClonehistoryLasthit,
    sUserLoginnameCloning,
    sUserFirstnameCloning,
    sUserLastnameCloning,
    sUserLoginnameCloned,
    sUserFirstnameCloned,
    sUserLastnameCloned,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
