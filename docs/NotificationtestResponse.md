# NotificationtestResponse

A Notificationtest Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiNotificationtestID** | **number** | The unique ID of the Notificationtest | [default to undefined]
**objNotificationtestName** | [**MultilingualNotificationtestName**](MultilingualNotificationtestName.md) |  | [default to undefined]
**fkiNotificationsubsectionID** | **number** | The unique ID of the Notificationsubsection | [default to undefined]
**sNotificationtestFunction** | **string** | The function name of the Notificationtest | [default to undefined]
**sNotificationtestNameX** | **string** | The name of the Notificationtest in the language of the requester | [default to undefined]

## Example

```typescript
import { NotificationtestResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: NotificationtestResponse = {
    pkiNotificationtestID,
    objNotificationtestName,
    fkiNotificationsubsectionID,
    sNotificationtestFunction,
    sNotificationtestNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
