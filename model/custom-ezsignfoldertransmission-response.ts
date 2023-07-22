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
import { CustomEzsignfoldertransmissionSignerResponse } from './custom-ezsignfoldertransmission-signer-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderStep } from './field-eezsignfolder-step';

/**
 * An Ezsignfolder Object in the context of an Ezsignbulksendtransmission
 * @export
 * @interface CustomEzsignfoldertransmissionResponse
 */
export interface CustomEzsignfoldertransmissionResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'pkiEzsignfolderID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'sEzsignfolderDescription': string;
    /**
     * 
     * @type {FieldEEzsignfolderStep}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'eEzsignfolderStep': FieldEEzsignfolderStep;
    /**
     * The number of total signatures that were requested in the Ezsignfolder
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'iEzsignfolderSignaturetotal': number;
    /**
     * The number of signatures that were signed in the Ezsignfolder.
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'iEzsignfolderSignaturesigned': number;
    /**
     * 
     * @type {Array<CustomEzsignfoldertransmissionSignerResponse>}
     * @memberof CustomEzsignfoldertransmissionResponse
     */
    'a_objEzsignfoldertransmissionSigner': Array<CustomEzsignfoldertransmissionSignerResponse>;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldertransmissionResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldertransmissionResponse
 */
export class DataObjectCustomEzsignfoldertransmissionResponse {
   pkiEzsignfolderID:number = 0
   sEzsignfolderDescription:string = ''
   eEzsignfolderStep:FieldEEzsignfolderStep = 'Unsent'
   iEzsignfolderSignaturetotal:number = 0
   iEzsignfolderSignaturesigned:number = 0
   a_objEzsignfoldertransmissionSigner:Array<CustomEzsignfoldertransmissionSignerResponse> = []
}

/**
 * @export 
 * A CustomEzsignfoldertransmissionResponse Validation Object
 * @class ValidationObjectCustomEzsignfoldertransmissionResponse
 */
export class ValidationObjectCustomEzsignfoldertransmissionResponse {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   eEzsignfolderStep = {
      type: 'enum',
      allowableValues: ['Unsent','PendingSend','Sent','PartiallySigned','Expired','Completed','Archived','Disposed'],
      required: true
   }
   iEzsignfolderSignaturetotal = {
      type: 'integer',
      required: true
   }
   iEzsignfolderSignaturesigned = {
      type: 'integer',
      required: true
   }
   a_objEzsignfoldertransmissionSigner = {
      type: 'array',
      required: true
   }
} 


