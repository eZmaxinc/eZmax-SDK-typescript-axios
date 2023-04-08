/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignSuggestTemplatesV1ResponseMPayload } from './ezsign-suggest-templates-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignSuggestTemplatesV1ResponseAllOf
 */
export interface EzsignSuggestTemplatesV1ResponseAllOf {
    /**
     * 
     * @type {EzsignSuggestTemplatesV1ResponseMPayload}
     * @memberof EzsignSuggestTemplatesV1ResponseAllOf
     */
    'mPayload': EzsignSuggestTemplatesV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignSuggestTemplatesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignSuggestTemplatesV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignSuggestTemplatesV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignSuggestTemplatesV1ResponseAllOf
 */
export class DataObjectEzsignSuggestTemplatesV1ResponseAllOf {
   mPayload:EzsignSuggestTemplatesV1ResponseMPayload = new DataObjectEzsignSuggestTemplatesV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignSuggestTemplatesV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignSuggestTemplatesV1ResponseAllOf
 */
export class ValidationObjectEzsignSuggestTemplatesV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignSuggestTemplatesV1ResponseMPayload()
} 


