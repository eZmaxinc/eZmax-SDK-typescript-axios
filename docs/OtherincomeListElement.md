# OtherincomeListElement

A Otherincome List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiOtherincomeID** | **number** | The unique ID of the Otherincome | [default to undefined]
**fkiOtherincometypeID** | **number** | The unique ID of the Otherincometype | [default to undefined]
**sOtherincometypeDescriptionX** | **string** | The description of the Otherincometype in the language of the requester | [default to undefined]
**sOtherincomeDescription** | **string** | The description of the Otherincome | [default to undefined]
**eOtherincomeRemunerationtype** | [**FieldEOtherincomeRemunerationtype**](FieldEOtherincomeRemunerationtype.md) |  | [default to undefined]
**dOtherincomeRemunerationsubtotal** | **string** | The remuneration subtotal of the Otherincome | [default to undefined]
**dOtherincomeRemunerationtaxes** | **string** | The remuneration total taxes of the Otherincome | [optional] [default to undefined]
**dOtherincomeRemunerationtotal** | **string** | The remuneration total of the Otherincome | [optional] [default to undefined]
**dtOtherincomePaid** | **string** | The paid of the Otherincome | [default to undefined]
**bOtherincomeIsactive** | **boolean** | Whether the otherincome is active or not | [default to undefined]

## Example

```typescript
import { OtherincomeListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: OtherincomeListElement = {
    pkiOtherincomeID,
    fkiOtherincometypeID,
    sOtherincometypeDescriptionX,
    sOtherincomeDescription,
    eOtherincomeRemunerationtype,
    dOtherincomeRemunerationsubtotal,
    dOtherincomeRemunerationtaxes,
    dOtherincomeRemunerationtotal,
    dtOtherincomePaid,
    bOtherincomeIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
