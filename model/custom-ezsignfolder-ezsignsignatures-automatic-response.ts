/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomEzsigndocumentEzsignsignaturesAutomaticResponse } from './custom-ezsigndocument-ezsignsignatures-automatic-response';

/**
 * An Ezsignfolder Object in the context of an EzsignsignaturesAutomatic path
 * @export
 * @interface CustomEzsignfolderEzsignsignaturesAutomaticResponse
 */
export interface CustomEzsignfolderEzsignsignaturesAutomaticResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzsignfolderEzsignsignaturesAutomaticResponse
     */
    /*'pkiEzsignfolderID': number;*/
    'pkiEzsignfolderID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzsignfolderEzsignsignaturesAutomaticResponse
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * 
     * @type {Array<CustomEzsigndocumentEzsignsignaturesAutomaticResponse>}
     * @memberof CustomEzsignfolderEzsignsignaturesAutomaticResponse
     */
    /*'a_objEzsigndocument': Array<CustomEzsigndocumentEzsignsignaturesAutomaticResponse>;*/
    'a_objEzsigndocument': Array<CustomEzsigndocumentEzsignsignaturesAutomaticResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfolderEzsignsignaturesAutomaticResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfolderEzsignsignaturesAutomaticResponse
 */
export class DataObjectCustomEzsignfolderEzsignsignaturesAutomaticResponse {
   pkiEzsignfolderID:number = 0
   sEzsignfolderDescription:string = ''
   a_objEzsigndocument:Array<CustomEzsigndocumentEzsignsignaturesAutomaticResponse> = []
}

/**
 * @export 
 * A CustomEzsignfolderEzsignsignaturesAutomaticResponse Validation Object
 * @class ValidationObjectCustomEzsignfolderEzsignsignaturesAutomaticResponse
 */
export class ValidationObjectCustomEzsignfolderEzsignsignaturesAutomaticResponse {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignfolderDescription = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   a_objEzsigndocument = {
      type: 'array',
      required: true
   }
} 


