# BrokerGetListV1ResponseMPayload

Payload for GET /1/object/broker/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objBroker** | [**Array&lt;BrokerListElement&gt;**](BrokerListElement.md) |  | [default to undefined]

## Example

```typescript
import { BrokerGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BrokerGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objBroker,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
