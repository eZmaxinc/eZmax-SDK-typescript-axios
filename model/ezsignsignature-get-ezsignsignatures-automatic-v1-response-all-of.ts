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
import { EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignsignature-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export interface EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf
     */
    'mPayload': EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload:EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


