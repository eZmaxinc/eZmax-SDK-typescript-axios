/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignfoldertransmissionResponse } from './custom-ezsignfoldertransmission-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionResponse } from './ezsignbulksendtransmission-response';

/**
 * @type EzsignbulksendtransmissionResponseCompound
 * An Ezsignbulksendtransmission Object and children to create a complete structure
 * @export
 */
/*export type EzsignbulksendtransmissionResponseCompound = EzsignbulksendtransmissionResponse;*/
export interface EzsignbulksendtransmissionResponseCompound {
    /**
     * The unique ID of the Ezsignbulksendtransmission
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    pkiEzsignbulksendtransmissionID:number 
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    fkiEzsignbulksendID:number 
    /**
     * The description of the Ezsignbulksendtransmission
     * @type {string}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    sEzsignbulksendtransmissionDescription:string 
    /**
     * The number of errors during the Ezsignbulksendtransmission
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    iEzsignbulksendtransmissionErrors:number 
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    objAudit:CommonAudit 
    /**
     * 
     * @type {Array<CustomEzsignfoldertransmissionResponse>}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    a_objEzsignfoldertransmission:Array<CustomEzsignfoldertransmissionResponse> 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionResponseCompound
 */
export class DataObjectEzsignbulksendtransmissionResponseCompound {
    pkiEzsignbulksendtransmissionID:number = 0
    fkiEzsignbulksendID:number = 0
    sEzsignbulksendtransmissionDescription:string = ''
    iEzsignbulksendtransmissionErrors:number = 0
    objAudit:CommonAudit = new DataObjectCommonAudit()
    a_objEzsignfoldertransmission:Array<CustomEzsignfoldertransmissionResponse> = []
}

/**
 * @export 
 * A EzsignbulksendtransmissionResponseCompound Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionResponseCompound
 */
export class ValidationObjectEzsignbulksendtransmissionResponseCompound {
   pkiEzsignbulksendtransmissionID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignbulksendtransmissionDescription = {
      type: 'string',
      required: true
   }
   iEzsignbulksendtransmissionErrors = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
   a_objEzsignfoldertransmission = {
      type: 'array',
      required: true
   }
} 


