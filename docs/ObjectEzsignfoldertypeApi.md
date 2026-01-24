# ObjectEzsignfoldertypeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignfoldertypeCreateObjectV3**](#ezsignfoldertypecreateobjectv3) | **POST** /3/object/ezsignfoldertype | Create a new Ezsignfoldertype|
|[**ezsignfoldertypeEditObjectV3**](#ezsignfoldertypeeditobjectv3) | **PUT** /3/object/ezsignfoldertype/{pkiEzsignfoldertypeID} | Edit an existing Ezsignfoldertype|
|[**ezsignfoldertypeGetAutocompleteV2**](#ezsignfoldertypegetautocompletev2) | **GET** /2/object/ezsignfoldertype/getAutocomplete/{sSelector} | Retrieve Ezsignfoldertypes and IDs|
|[**ezsignfoldertypeGetListV1**](#ezsignfoldertypegetlistv1) | **GET** /1/object/ezsignfoldertype/getList | Retrieve Ezsignfoldertype list|
|[**ezsignfoldertypeGetObjectV2**](#ezsignfoldertypegetobjectv2) | **GET** /2/object/ezsignfoldertype/{pkiEzsignfoldertypeID} | Retrieve an existing Ezsignfoldertype|
|[**ezsignfoldertypeGetObjectV4**](#ezsignfoldertypegetobjectv4) | **GET** /4/object/ezsignfoldertype/{pkiEzsignfoldertypeID} | Retrieve an existing Ezsignfoldertype|

# **ezsignfoldertypeCreateObjectV3**
> EzsignfoldertypeCreateObjectV3Response ezsignfoldertypeCreateObjectV3(ezsignfoldertypeCreateObjectV3Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration,
    EzsignfoldertypeCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let ezsignfoldertypeCreateObjectV3Request: EzsignfoldertypeCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsignfoldertypeCreateObjectV3(
    ezsignfoldertypeCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldertypeCreateObjectV3Request** | **EzsignfoldertypeCreateObjectV3Request**|  | |


### Return type

**EzsignfoldertypeCreateObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldertypeEditObjectV3**
> EzsignfoldertypeEditObjectV3Response ezsignfoldertypeEditObjectV3(ezsignfoldertypeEditObjectV3Request)



### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration,
    EzsignfoldertypeEditObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let pkiEzsignfoldertypeID: number; // (default to undefined)
let ezsignfoldertypeEditObjectV3Request: EzsignfoldertypeEditObjectV3Request; //

const { status, data } = await apiInstance.ezsignfoldertypeEditObjectV3(
    pkiEzsignfoldertypeID,
    ezsignfoldertypeEditObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldertypeEditObjectV3Request** | **EzsignfoldertypeEditObjectV3Request**|  | |
| **pkiEzsignfoldertypeID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldertypeEditObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldertypeGetAutocompleteV2**
> EzsignfoldertypeGetAutocompleteV2Response ezsignfoldertypeGetAutocompleteV2()

Get the list of Ezsignfoldertype to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let sSelector: 'Active' | 'All' | 'EzsigntemplateEdit' | 'EzsigntemplateUsergroup'; //The type of Ezsignfoldertypes to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignfoldertypeGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;Active&#39; | &#39;All&#39; | &#39;EzsigntemplateEdit&#39; | &#39;EzsigntemplateUsergroup&#39;**]**Array<&#39;Active&#39; &#124; &#39;All&#39; &#124; &#39;EzsigntemplateEdit&#39; &#124; &#39;EzsigntemplateUsergroup&#39;>** | The type of Ezsignfoldertypes to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**EzsignfoldertypeGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldertypeGetListV1**
> EzsignfoldertypeGetListV1Response ezsignfoldertypeGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |

### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let eOrderBy: 'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignfoldertypeGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzsignfoldertypeID_ASC&#39; | &#39;pkiEzsignfoldertypeID_DESC&#39; | &#39;eEzsignfoldertypePrivacylevel_ASC&#39; | &#39;eEzsignfoldertypePrivacylevel_DESC&#39; | &#39;sEzsignfoldertypeNameX_ASC&#39; | &#39;sEzsignfoldertypeNameX_DESC&#39; | &#39;bEzsignfoldertypeIsactive_ASC&#39; | &#39;bEzsignfoldertypeIsactive_DESC&#39;**]**Array<&#39;pkiEzsignfoldertypeID_ASC&#39; &#124; &#39;pkiEzsignfoldertypeID_DESC&#39; &#124; &#39;eEzsignfoldertypePrivacylevel_ASC&#39; &#124; &#39;eEzsignfoldertypePrivacylevel_DESC&#39; &#124; &#39;sEzsignfoldertypeNameX_ASC&#39; &#124; &#39;sEzsignfoldertypeNameX_DESC&#39; &#124; &#39;bEzsignfoldertypeIsactive_ASC&#39; &#124; &#39;bEzsignfoldertypeIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsignfoldertypeGetListV1Response**

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

# **ezsignfoldertypeGetObjectV2**
> EzsignfoldertypeGetObjectV2Response ezsignfoldertypeGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let pkiEzsignfoldertypeID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldertypeGetObjectV2(
    pkiEzsignfoldertypeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldertypeID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldertypeGetObjectV2Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldertypeGetObjectV4**
> EzsignfoldertypeGetObjectV4Response ezsignfoldertypeGetObjectV4()



### Example

```typescript
import {
    ObjectEzsignfoldertypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldertypeApi(configuration);

let pkiEzsignfoldertypeID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldertypeGetObjectV4(
    pkiEzsignfoldertypeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldertypeID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldertypeGetObjectV4Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

