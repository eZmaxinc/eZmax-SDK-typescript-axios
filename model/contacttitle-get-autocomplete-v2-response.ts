/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { ContacttitleGetAutocompleteV2ResponseMPayload } from './contacttitle-get-autocomplete-v2-response-mpayload';

/**
 * @type ContacttitleGetAutocompleteV2Response
 * Response for GET /2/object/contacttitle/getAutocomplete
 * @export
 */
/*export type ContacttitleGetAutocompleteV2Response = CommonResponse;*/
export interface ContacttitleGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ContacttitleGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ContacttitleGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ContacttitleGetAutocompleteV2ResponseMPayload}
     * @memberof ContacttitleGetAutocompleteV2Response
     */
    mPayload:ContacttitleGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectContacttitleGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectContacttitleGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A ContacttitleGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContacttitleGetAutocompleteV2Response
 */
export class DataObjectContacttitleGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ContacttitleGetAutocompleteV2ResponseMPayload = new DataObjectContacttitleGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A ContacttitleGetAutocompleteV2Response Validation Object
 * @class ValidationObjectContacttitleGetAutocompleteV2Response
 */
export class ValidationObjectContacttitleGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectContacttitleGetAutocompleteV2ResponseMPayload()
} 


