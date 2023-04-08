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
import { EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignfolder-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export interface EzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload:EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


