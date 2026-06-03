# ObjectEzmaxpartnerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxpartnerGetCustomDeveloppersV1**](#ezmaxpartnergetcustomdeveloppersv1) | **GET** /1/object/ezmaxpartner/getCustomDeveloppers | Retrieve Ezmaxpartner custom developpers list|
|[**ezmaxpartnerGetObjectV2**](#ezmaxpartnergetobjectv2) | **GET** /2/object/ezmaxpartner/{pkiEzmaxpartnerID} | Retrieve an existing Ezmaxpartner|

# **ezmaxpartnerGetCustomDeveloppersV1**
> EzmaxpartnerGetCustomDeveloppersV1Response ezmaxpartnerGetCustomDeveloppersV1()


### Example

```typescript
import {
    ObjectEzmaxpartnerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerApi(configuration);

let eOrderBy: 'pkiEzmaxpartnerID_ASC' | 'pkiEzmaxpartnerID_DESC' | 'sEzmaxpartnerAddressX_ASC' | 'sEzmaxpartnerAddressX_DESC' | 'sEzmaxpartnerEmailaddressX_ASC' | 'sEzmaxpartnerEmailaddressX_DESC' | 'sEzmaxpartnerShortdescriptionX_ASC' | 'sEzmaxpartnerShortdescriptionX_DESC' | 'sEzmaxpartnerNameX_ASC' | 'sEzmaxpartnerNameX_DESC' | 'sEzmaxpartnerPhoneE164X_ASC' | 'sEzmaxpartnerPhoneE164X_DESC' | 'sEzmaxpartnerUrlX_ASC' | 'sEzmaxpartnerUrlX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerGetCustomDeveloppersV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzmaxpartnerID_ASC&#39; | &#39;pkiEzmaxpartnerID_DESC&#39; | &#39;sEzmaxpartnerAddressX_ASC&#39; | &#39;sEzmaxpartnerAddressX_DESC&#39; | &#39;sEzmaxpartnerEmailaddressX_ASC&#39; | &#39;sEzmaxpartnerEmailaddressX_DESC&#39; | &#39;sEzmaxpartnerShortdescriptionX_ASC&#39; | &#39;sEzmaxpartnerShortdescriptionX_DESC&#39; | &#39;sEzmaxpartnerNameX_ASC&#39; | &#39;sEzmaxpartnerNameX_DESC&#39; | &#39;sEzmaxpartnerPhoneE164X_ASC&#39; | &#39;sEzmaxpartnerPhoneE164X_DESC&#39; | &#39;sEzmaxpartnerUrlX_ASC&#39; | &#39;sEzmaxpartnerUrlX_DESC&#39;**]**Array<&#39;pkiEzmaxpartnerID_ASC&#39; &#124; &#39;pkiEzmaxpartnerID_DESC&#39; &#124; &#39;sEzmaxpartnerAddressX_ASC&#39; &#124; &#39;sEzmaxpartnerAddressX_DESC&#39; &#124; &#39;sEzmaxpartnerEmailaddressX_ASC&#39; &#124; &#39;sEzmaxpartnerEmailaddressX_DESC&#39; &#124; &#39;sEzmaxpartnerShortdescriptionX_ASC&#39; &#124; &#39;sEzmaxpartnerShortdescriptionX_DESC&#39; &#124; &#39;sEzmaxpartnerNameX_ASC&#39; &#124; &#39;sEzmaxpartnerNameX_DESC&#39; &#124; &#39;sEzmaxpartnerPhoneE164X_ASC&#39; &#124; &#39;sEzmaxpartnerPhoneE164X_DESC&#39; &#124; &#39;sEzmaxpartnerUrlX_ASC&#39; &#124; &#39;sEzmaxpartnerUrlX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzmaxpartnerGetCustomDeveloppersV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezmaxpartnerGetObjectV2**
> EzmaxpartnerGetObjectV2Response ezmaxpartnerGetObjectV2()



### Example

```typescript
import {
    ObjectEzmaxpartnerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerApi(configuration);

let pkiEzmaxpartnerID: number; //The unique ID of the Ezmaxpartner (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerGetObjectV2(
    pkiEzmaxpartnerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzmaxpartnerID** | [**number**] | The unique ID of the Ezmaxpartner | defaults to undefined|


### Return type

**EzmaxpartnerGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

