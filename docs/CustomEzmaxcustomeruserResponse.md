# CustomEzmaxcustomeruserResponse

A Ezmaxcustomeruser Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objEzmaxcustomer** | [**CustomEzmaxcustomerResponse**](CustomEzmaxcustomerResponse.md) |  | [default to undefined]
**fkiContacttitleID** | **number** | The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)| | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**objEmail** | [**EmailResponseCompound**](EmailResponseCompound.md) |  | [optional] [default to undefined]
**objPhone** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]
**sEzmaxcustomeruserFirstname** | **string** | The First name of the Ezmaxcustomeruser | [default to undefined]
**sEzmaxcustomeruserLastname** | **string** | The First name of the Ezmaxcustomeruser | [default to undefined]

## Example

```typescript
import { CustomEzmaxcustomeruserResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzmaxcustomeruserResponse = {
    objEzmaxcustomer,
    fkiContacttitleID,
    fkiLanguageID,
    objEmail,
    objPhone,
    sEzmaxcustomeruserFirstname,
    sEzmaxcustomeruserLastname,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
