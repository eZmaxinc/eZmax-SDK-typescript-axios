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
import { CommunicationreferenceRequest } from './communicationreference-request';

/**
 * @type CommunicationreferenceRequestCompound
 * A Communicationreference Object and children
 * @export
 */
/*export type CommunicationreferenceRequestCompound = CommunicationreferenceRequest;*/
export interface CommunicationreferenceRequestCompound {
    /**
     * The unique ID of the Communicationreference
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    pkiCommunicationreferenceID?:number 
    /**
     * The unique ID of the Buyercontract
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiBuyercontractID?:number 
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiEzsignfolderID?:number 
    /**
     * The unique ID of the Inscription.
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiInscriptionID?:number 
    /**
     * The unique ID of the Inscriptiontemp
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiInscriptiontempID?:number 
    /**
     * The unique ID of the Invoice.
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiInvoiceID?:number 
    /**
     * The unique ID of the Otherincome
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiOtherincomeID?:number 
    /**
     * The unique ID of the Electronicfundstransfer
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiElectronicfundstransferID?:number 
    /**
     * The unique ID of the Rejectedoffertopurchase
     * @type {number}
     * @memberof CommunicationreferenceRequestCompound
     */
    fkiRejectedoffertopurchaseID?:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommunicationreferenceRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationreferenceRequestCompound
 */
export class DataObjectCommunicationreferenceRequestCompound {
    pkiCommunicationreferenceID?:number = undefined
    fkiBuyercontractID?:number = undefined
    fkiEzsignfolderID?:number = undefined
    fkiInscriptionID?:number = undefined
    fkiInscriptiontempID?:number = undefined
    fkiInvoiceID?:number = undefined
    fkiOtherincomeID?:number = undefined
    fkiElectronicfundstransferID?:number = undefined
    fkiRejectedoffertopurchaseID?:number = undefined
}

/**
 * @export 
 * A CommunicationreferenceRequestCompound Validation Object
 * @class ValidationObjectCommunicationreferenceRequestCompound
 */
export class ValidationObjectCommunicationreferenceRequestCompound {
   pkiCommunicationreferenceID = {
      type: 'integer',
      minimum: 0,
      maximum: 4294967295,
      required: false
   }
   fkiBuyercontractID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiInscriptionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiInscriptiontempID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: false
   }
   fkiInvoiceID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiOtherincomeID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiElectronicfundstransferID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiRejectedoffertopurchaseID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
} 


