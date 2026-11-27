# ObjectBrandingApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**brandingCreateObjectV2**](#brandingcreateobjectv2) | **POST** /2/object/branding | Create a new Branding|
|[**brandingEditObjectV2**](#brandingeditobjectv2) | **PUT** /2/object/branding/{pkiBrandingID} | Edit an existing Branding|
|[**brandingGetAutocompleteV2**](#brandinggetautocompletev2) | **GET** /2/object/branding/getAutocomplete/{sSelector} | Retrieve Brandings and IDs|
|[**brandingGetListV1**](#brandinggetlistv1) | **GET** /1/object/branding/getList | Retrieve Branding list|
|[**brandingGetObjectV3**](#brandinggetobjectv3) | **GET** /3/object/branding/{pkiBrandingID} | Retrieve an existing Branding|

# **brandingCreateObjectV2**
> BrandingCreateObjectV2Response brandingCreateObjectV2(brandingCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectBrandingApi,
    Configuration,
    BrandingCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrandingApi(configuration);

let brandingCreateObjectV2Request: BrandingCreateObjectV2Request; //

const { status, data } = await apiInstance.brandingCreateObjectV2(
    brandingCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **brandingCreateObjectV2Request** | **BrandingCreateObjectV2Request**|  | |


### Return type

**BrandingCreateObjectV2Response**

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

# **brandingEditObjectV2**
> BrandingEditObjectV2Response brandingEditObjectV2(brandingEditObjectV2Request)



### Example

```typescript
import {
    ObjectBrandingApi,
    Configuration,
    BrandingEditObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrandingApi(configuration);

let pkiBrandingID: number; // (default to undefined)
let brandingEditObjectV2Request: BrandingEditObjectV2Request; //

const { status, data } = await apiInstance.brandingEditObjectV2(
    pkiBrandingID,
    brandingEditObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **brandingEditObjectV2Request** | **BrandingEditObjectV2Request**|  | |
| **pkiBrandingID** | [**number**] |  | defaults to undefined|


### Return type

**BrandingEditObjectV2Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **brandingGetAutocompleteV2**
> BrandingGetAutocompleteV2Response brandingGetAutocompleteV2()

Get the list of Branding to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectBrandingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrandingApi(configuration);

let sSelector: 'All'; //The type of Brandings to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.brandingGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Brandings to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**BrandingGetAutocompleteV2Response**

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

# **brandingGetListV1**
> BrandingGetListV1Response brandingGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBrandingLogo | Default<br>JPEG<br>PNG | | eBrandingLogointerface | Default<br>JPEG<br>PNG |

### Example

```typescript
import {
    ObjectBrandingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrandingApi(configuration);

let eOrderBy: 'pkiBrandingID_ASC' | 'pkiBrandingID_DESC' | 'sBrandingDescriptionX_ASC' | 'sBrandingDescriptionX_DESC' | 'iBrandingColortext_ASC' | 'iBrandingColortext_DESC' | 'iBrandingColortextlinkbox_ASC' | 'iBrandingColortextlinkbox_DESC' | 'iBrandingColortextbutton_ASC' | 'iBrandingColortextbutton_DESC' | 'iBrandingColorbackground_ASC' | 'iBrandingColorbackground_DESC' | 'iBrandingColorbackgroundbutton_ASC' | 'iBrandingColorbackgroundbutton_DESC' | 'iBrandingColorbackgroundsmallbox_ASC' | 'iBrandingColorbackgroundsmallbox_DESC' | 'bBrandingIsactive_ASC' | 'bBrandingIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.brandingGetListV1(
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
| **eOrderBy** | [**&#39;pkiBrandingID_ASC&#39; | &#39;pkiBrandingID_DESC&#39; | &#39;sBrandingDescriptionX_ASC&#39; | &#39;sBrandingDescriptionX_DESC&#39; | &#39;iBrandingColortext_ASC&#39; | &#39;iBrandingColortext_DESC&#39; | &#39;iBrandingColortextlinkbox_ASC&#39; | &#39;iBrandingColortextlinkbox_DESC&#39; | &#39;iBrandingColortextbutton_ASC&#39; | &#39;iBrandingColortextbutton_DESC&#39; | &#39;iBrandingColorbackground_ASC&#39; | &#39;iBrandingColorbackground_DESC&#39; | &#39;iBrandingColorbackgroundbutton_ASC&#39; | &#39;iBrandingColorbackgroundbutton_DESC&#39; | &#39;iBrandingColorbackgroundsmallbox_ASC&#39; | &#39;iBrandingColorbackgroundsmallbox_DESC&#39; | &#39;bBrandingIsactive_ASC&#39; | &#39;bBrandingIsactive_DESC&#39;**]**Array<&#39;pkiBrandingID_ASC&#39; &#124; &#39;pkiBrandingID_DESC&#39; &#124; &#39;sBrandingDescriptionX_ASC&#39; &#124; &#39;sBrandingDescriptionX_DESC&#39; &#124; &#39;iBrandingColortext_ASC&#39; &#124; &#39;iBrandingColortext_DESC&#39; &#124; &#39;iBrandingColortextlinkbox_ASC&#39; &#124; &#39;iBrandingColortextlinkbox_DESC&#39; &#124; &#39;iBrandingColortextbutton_ASC&#39; &#124; &#39;iBrandingColortextbutton_DESC&#39; &#124; &#39;iBrandingColorbackground_ASC&#39; &#124; &#39;iBrandingColorbackground_DESC&#39; &#124; &#39;iBrandingColorbackgroundbutton_ASC&#39; &#124; &#39;iBrandingColorbackgroundbutton_DESC&#39; &#124; &#39;iBrandingColorbackgroundsmallbox_ASC&#39; &#124; &#39;iBrandingColorbackgroundsmallbox_DESC&#39; &#124; &#39;bBrandingIsactive_ASC&#39; &#124; &#39;bBrandingIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**BrandingGetListV1Response**

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

# **brandingGetObjectV3**
> BrandingGetObjectV3Response brandingGetObjectV3()



### Example

```typescript
import {
    ObjectBrandingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrandingApi(configuration);

let pkiBrandingID: number; // (default to undefined)

const { status, data } = await apiInstance.brandingGetObjectV3(
    pkiBrandingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBrandingID** | [**number**] |  | defaults to undefined|


### Return type

**BrandingGetObjectV3Response**

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

