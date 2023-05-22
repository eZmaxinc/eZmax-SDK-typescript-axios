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
import { EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignbulksend-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export interface EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf
     */
    'mPayload': EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload:EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


