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
import type { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

/**
 * An Ezsignsignature Object in the context of an EzsignsignaturesAutomatic path
 * @export
 * @interface CustomEzsignsignatureEzsignsignaturesAutomaticResponse
 */
export interface CustomEzsignsignatureEzsignsignaturesAutomaticResponse {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof CustomEzsignsignatureEzsignsignaturesAutomaticResponse
     */
    /*'pkiEzsignsignatureID': number;*/
    'pkiEzsignsignatureID': number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof CustomEzsignsignatureEzsignsignaturesAutomaticResponse
     */
    /*'eEzsignsignatureType': FieldEEzsignsignatureType;*/
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof CustomEzsignsignatureEzsignsignaturesAutomaticResponse
     */
    /*'iEzsignpagePagenumber': number;*/
    'iEzsignpagePagenumber': number;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignsignatureEzsignsignaturesAutomaticResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignsignatureEzsignsignaturesAutomaticResponse
 */
export class DataObjectCustomEzsignsignatureEzsignsignaturesAutomaticResponse {
   pkiEzsignsignatureID:number = 0
   eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
   iEzsignpagePagenumber:number = 0
}

/**
 * @export 
 * A CustomEzsignsignatureEzsignsignaturesAutomaticResponse Validation Object
 * @class ValidationObjectCustomEzsignsignatureEzsignsignaturesAutomaticResponse
 */
export class ValidationObjectCustomEzsignsignatureEzsignsignaturesAutomaticResponse {
   pkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsignsignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea','Consultation','Signature'],
      required: true
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
} 


