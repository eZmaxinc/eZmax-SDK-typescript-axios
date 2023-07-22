/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureCreateObjectV2ResponseMPayload } from './ezsignsignature-create-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignsignatureCreateObjectV2ResponseAllOf
 */
export interface EzsignsignatureCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureCreateObjectV2ResponseMPayload}
     * @memberof EzsignsignatureCreateObjectV2ResponseAllOf
     */
    'mPayload': EzsignsignatureCreateObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureCreateObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureCreateObjectV2ResponseAllOf
 */
export class DataObjectEzsignsignatureCreateObjectV2ResponseAllOf {
   mPayload:EzsignsignatureCreateObjectV2ResponseMPayload = new DataObjectEzsignsignatureCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureCreateObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsignsignatureCreateObjectV2ResponseAllOf
 */
export class ValidationObjectEzsignsignatureCreateObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsignsignatureCreateObjectV2ResponseMPayload()
} 


