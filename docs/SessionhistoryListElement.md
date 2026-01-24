# SessionhistoryListElement

A Sessionhistory List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSessionhistoryID** | **number** | The unique ID of the Sessionhistory | [default to undefined]
**fkiComputerID** | **number** | The unique ID of the Computer | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**dtSessionhistoryFirsthit** | **string** | The first hit of the Sessionhistory | [default to undefined]
**dtSessionhistoryLasthit** | **string** | The last hit of the Sessionhistory | [default to undefined]
**eSessionhistoryEndby** | [**FieldESessionhistoryEndby**](FieldESessionhistoryEndby.md) |  | [default to undefined]
**sComputerDescription** | **string** | The description of the Computer | [optional] [default to undefined]
**sSessionhistoryDuration** | **string** | The duration of the session | [default to undefined]
**sSessionhistoryIP** | **string** | Represent an IP address. | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [optional] [default to undefined]

## Example

```typescript
import { SessionhistoryListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SessionhistoryListElement = {
    pkiSessionhistoryID,
    fkiComputerID,
    fkiUserID,
    dtSessionhistoryFirsthit,
    dtSessionhistoryLasthit,
    eSessionhistoryEndby,
    sComputerDescription,
    sSessionhistoryDuration,
    sSessionhistoryIP,
    sUserLoginname,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
