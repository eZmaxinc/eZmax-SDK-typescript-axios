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
import { EzsignfolderCreateObjectV2ResponseMPayload } from './ezsignfolder-create-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderCreateObjectV2ResponseAllOf
 */
export interface EzsignfolderCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderCreateObjectV2ResponseMPayload}
     * @memberof EzsignfolderCreateObjectV2ResponseAllOf
     */
    'mPayload': EzsignfolderCreateObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderCreateObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderCreateObjectV2ResponseAllOf
 */
export class DataObjectEzsignfolderCreateObjectV2ResponseAllOf {
   mPayload:EzsignfolderCreateObjectV2ResponseMPayload = new DataObjectEzsignfolderCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderCreateObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderCreateObjectV2ResponseAllOf
 */
export class ValidationObjectEzsignfolderCreateObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderCreateObjectV2ResponseMPayload()
} 


