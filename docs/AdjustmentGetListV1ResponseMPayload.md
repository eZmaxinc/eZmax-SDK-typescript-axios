# AdjustmentGetListV1ResponseMPayload

Payload for GET /1/object/adjustment/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objAdjustment** | [**Array&lt;AdjustmentListElement&gt;**](AdjustmentListElement.md) |  | [default to undefined]

## Example

```typescript
import { AdjustmentGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AdjustmentGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objAdjustment,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
