# DisclosureListElement

A Disclosure List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDisclosureID** | **number** | The unique ID of the Disclosure | [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**eDisclosureInteresttype** | [**FieldEDisclosureInteresttype**](FieldEDisclosureInteresttype.md) |  | [default to undefined]
**sDisclosureRelation** | **string** | The relation of the Disclosure | [default to undefined]
**dtDisclosureRedactiondate** | **string** | The redactiondate of the Disclosure | [default to undefined]
**dtDisclosureAcceptationdate** | **string** | The acceptationdate of the Disclosure | [default to undefined]
**dtDisclosureReceptiondate** | **string** | The receptiondate of the Disclosure | [default to undefined]
**bDisclosureIsactive** | **boolean** | Whether the disclosure is active or not | [default to undefined]
**sDisclosureNumber** | **string** | The number of a Disclosure | [optional] [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [optional] [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [optional] [default to undefined]
**sBrokerName** | **string** | The name of the Broker | [optional] [default to undefined]

## Example

```typescript
import { DisclosureListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DisclosureListElement = {
    pkiDisclosureID,
    fkiAgentID,
    fkiBrokerID,
    eDisclosureInteresttype,
    sDisclosureRelation,
    dtDisclosureRedactiondate,
    dtDisclosureAcceptationdate,
    dtDisclosureReceptiondate,
    bDisclosureIsactive,
    sDisclosureNumber,
    sContactFirstname,
    sContactLastname,
    sBrokerName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
