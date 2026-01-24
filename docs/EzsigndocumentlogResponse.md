# EzsigndocumentlogResponse

An Ezsigndocumentlog Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiEzsignsignerID** | **number** | The unique ID of the Ezsignsigner | [optional] [default to undefined]
**dtEzsigndocumentlogDatetime** | **string** | The date and time at which the event was logged | [default to undefined]
**eEzsigndocumentlogType** | [**FieldEEzsigndocumentlogType**](FieldEEzsigndocumentlogType.md) |  | [default to undefined]
**sEzsigndocumentlogDetail** | **string** | The detail of the Ezsigndocumentlog | [default to undefined]
**sEzsigndocumentlogLastname** | **string** | The last name of the User or Ezsignsigner | [default to undefined]
**sEzsigndocumentlogFirstname** | **string** | The first name of the User or Ezsignsigner | [default to undefined]
**sEzsigndocumentlogIP** | **string** | Represent an IP address. | [default to undefined]

## Example

```typescript
import { EzsigndocumentlogResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentlogResponse = {
    fkiUserID,
    fkiEzsignsignerID,
    dtEzsigndocumentlogDatetime,
    eEzsigndocumentlogType,
    sEzsigndocumentlogDetail,
    sEzsigndocumentlogLastname,
    sEzsigndocumentlogFirstname,
    sEzsigndocumentlogIP,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
