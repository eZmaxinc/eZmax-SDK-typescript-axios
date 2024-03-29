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
import { EzsignsignatureGetObjectV2ResponseMPayload } from './ezsignsignature-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignsignatureGetObjectV2ResponseAllOf
 */
export interface EzsignsignatureGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureGetObjectV2ResponseMPayload}
     * @memberof EzsignsignatureGetObjectV2ResponseAllOf
     */
    'mPayload': EzsignsignatureGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetObjectV2ResponseAllOf
 */
export class DataObjectEzsignsignatureGetObjectV2ResponseAllOf {
   mPayload:EzsignsignatureGetObjectV2ResponseMPayload = new DataObjectEzsignsignatureGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsignsignatureGetObjectV2ResponseAllOf
 */
export class ValidationObjectEzsignsignatureGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload()
} 


