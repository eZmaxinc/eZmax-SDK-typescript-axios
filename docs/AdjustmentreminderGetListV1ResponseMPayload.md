# AdjustmentreminderGetListV1ResponseMPayload

Payload for GET /1/object/adjustmentreminder/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objAdjustmentreminder** | [**Array&lt;AdjustmentreminderListElement&gt;**](AdjustmentreminderListElement.md) |  | [default to undefined]

## Example

```typescript
import { AdjustmentreminderGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AdjustmentreminderGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objAdjustmentreminder,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
