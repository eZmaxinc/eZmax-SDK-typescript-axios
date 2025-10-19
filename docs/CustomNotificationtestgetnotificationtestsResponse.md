# CustomNotificationtestgetnotificationtestsResponse

A Notificationtest Object in the context of getNotificationtests

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiNotificationtestID** | **number** | The unique ID of the Notificationtest | [default to undefined]
**objNotificationtestName** | [**MultilingualNotificationtestName**](MultilingualNotificationtestName.md) |  | [default to undefined]
**fkiNotificationsubsectionID** | **number** | The unique ID of the Notificationsubsection | [default to undefined]
**sNotificationtestFunction** | **string** | The function name of the Notificationtest | [default to undefined]
**sNotificationtestNameX** | **string** | The name of the Notificationtest in the language of the requester | [default to undefined]
**eNotificationpreferenceStatus** | [**FieldENotificationpreferenceStatus**](FieldENotificationpreferenceStatus.md) |  | [default to undefined]
**iNotificationtest** | **number** | The number of elements returned by the Notificationtest | [default to undefined]

## Example

```typescript
import { CustomNotificationtestgetnotificationtestsResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomNotificationtestgetnotificationtestsResponse = {
    pkiNotificationtestID,
    objNotificationtestName,
    fkiNotificationsubsectionID,
    sNotificationtestFunction,
    sNotificationtestNameX,
    eNotificationpreferenceStatus,
    iNotificationtest,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
