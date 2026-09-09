# ObjectVariableexpenseApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**variableexpenseCreateObjectV1**](#variableexpensecreateobjectv1) | **POST** /1/object/variableexpense | Create a new Variableexpense|
|[**variableexpenseEditObjectV1**](#variableexpenseeditobjectv1) | **PUT** /1/object/variableexpense/{pkiVariableexpenseID} | Edit an existing Variableexpense|
|[**variableexpenseGetAutocompleteV2**](#variableexpensegetautocompletev2) | **GET** /2/object/variableexpense/getAutocomplete/{sSelector} | Retrieve Variableexpenses and IDs|
|[**variableexpenseGetListV1**](#variableexpensegetlistv1) | **GET** /1/object/variableexpense/getList | Retrieve Variableexpense list|
|[**variableexpenseGetObjectV2**](#variableexpensegetobjectv2) | **GET** /2/object/variableexpense/{pkiVariableexpenseID} | Retrieve an existing Variableexpense|

# **variableexpenseCreateObjectV1**
> VariableexpenseCreateObjectV1Response variableexpenseCreateObjectV1(variableexpenseCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectVariableexpenseApi,
    Configuration,
    VariableexpenseCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectVariableexpenseApi(configuration);

let variableexpenseCreateObjectV1Request: VariableexpenseCreateObjectV1Request; //

const { status, data } = await apiInstance.variableexpenseCreateObjectV1(
    variableexpenseCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **variableexpenseCreateObjectV1Request** | **VariableexpenseCreateObjectV1Request**|  | |


### Return type

**VariableexpenseCreateObjectV1Response**

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

# **variableexpenseEditObjectV1**
> VariableexpenseEditObjectV1Response variableexpenseEditObjectV1(variableexpenseEditObjectV1Request)



### Example

```typescript
import {
    ObjectVariableexpenseApi,
    Configuration,
    VariableexpenseEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectVariableexpenseApi(configuration);

let pkiVariableexpenseID: number; // (default to undefined)
let variableexpenseEditObjectV1Request: VariableexpenseEditObjectV1Request; //

const { status, data } = await apiInstance.variableexpenseEditObjectV1(
    pkiVariableexpenseID,
    variableexpenseEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **variableexpenseEditObjectV1Request** | **VariableexpenseEditObjectV1Request**|  | |
| **pkiVariableexpenseID** | [**number**] |  | defaults to undefined|


### Return type

**VariableexpenseEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **variableexpenseGetAutocompleteV2**
> VariableexpenseGetAutocompleteV2Response variableexpenseGetAutocompleteV2()

Get the list of Variableexpense to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectVariableexpenseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectVariableexpenseApi(configuration);

let sSelector: 'All'; //The type of Variableexpenses to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.variableexpenseGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Variableexpenses to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**VariableexpenseGetAutocompleteV2Response**

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

# **variableexpenseGetListV1**
> VariableexpenseGetListV1Response variableexpenseGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eVariableexpenseTaxable | Yes<br>No<br>Included |

### Example

```typescript
import {
    ObjectVariableexpenseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectVariableexpenseApi(configuration);

let eOrderBy: 'pkiVariableexpenseID_ASC' | 'pkiVariableexpenseID_DESC' | 'sVariableexpenseCode_ASC' | 'sVariableexpenseCode_DESC' | 'sVariableexpenseDescriptionX_ASC' | 'sVariableexpenseDescriptionX_DESC' | 'eVariableexpenseTaxable_ASC' | 'eVariableexpenseTaxable_DESC' | 'bVariableexpenseIsactive_ASC' | 'bVariableexpenseIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.variableexpenseGetListV1(
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
| **eOrderBy** | [**&#39;pkiVariableexpenseID_ASC&#39; | &#39;pkiVariableexpenseID_DESC&#39; | &#39;sVariableexpenseCode_ASC&#39; | &#39;sVariableexpenseCode_DESC&#39; | &#39;sVariableexpenseDescriptionX_ASC&#39; | &#39;sVariableexpenseDescriptionX_DESC&#39; | &#39;eVariableexpenseTaxable_ASC&#39; | &#39;eVariableexpenseTaxable_DESC&#39; | &#39;bVariableexpenseIsactive_ASC&#39; | &#39;bVariableexpenseIsactive_DESC&#39;**]**Array<&#39;pkiVariableexpenseID_ASC&#39; &#124; &#39;pkiVariableexpenseID_DESC&#39; &#124; &#39;sVariableexpenseCode_ASC&#39; &#124; &#39;sVariableexpenseCode_DESC&#39; &#124; &#39;sVariableexpenseDescriptionX_ASC&#39; &#124; &#39;sVariableexpenseDescriptionX_DESC&#39; &#124; &#39;eVariableexpenseTaxable_ASC&#39; &#124; &#39;eVariableexpenseTaxable_DESC&#39; &#124; &#39;bVariableexpenseIsactive_ASC&#39; &#124; &#39;bVariableexpenseIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**VariableexpenseGetListV1Response**

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

# **variableexpenseGetObjectV2**
> VariableexpenseGetObjectV2Response variableexpenseGetObjectV2()



### Example

```typescript
import {
    ObjectVariableexpenseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectVariableexpenseApi(configuration);

let pkiVariableexpenseID: number; // (default to undefined)

const { status, data } = await apiInstance.variableexpenseGetObjectV2(
    pkiVariableexpenseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiVariableexpenseID** | [**number**] |  | defaults to undefined|


### Return type

**VariableexpenseGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

