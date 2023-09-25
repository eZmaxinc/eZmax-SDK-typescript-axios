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
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingcommissionResponse } from './ezmaxinvoicingcommission-response';

/**
 * @type EzmaxinvoicingcommissionResponseCompound
 * A Ezmaxinvoicingcommission Object
 * @export
 */
/** export type EzmaxinvoicingcommissionResponseCompound = EzmaxinvoicingcommissionResponse; */
export interface EzmaxinvoicingcommissionResponseCompound {
    /**
     * The unique ID of the Ezmaxinvoicingcommission
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    pkiEzmaxinvoicingcommissionID?:number 
    /**
     * The unique ID of the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    fkiEzmaxinvoicingsummaryglobalID?:number 
    /**
     * The unique ID of the Ezmaxpartner
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    fkiEzmaxpartnerID?:number 
    /**
     * The unique ID of the Ezmaxrepresentative
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    fkiEzmaxrepresentativeID?:number 
    /**
     * The start date for the Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    dtEzmaxinvoicingcommissionStart:string 
    /**
     * The end date for the Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    dtEzmaxinvoicingcommissionEnd:string 
    /**
     * This is the number of days during the month on which the Ezmaxinvoigcommission applies
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    iEzmaxinvoicingcommissionDays:number 
    /**
     * The amount of Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    dEzmaxinvoicingcommissionAmount:string 
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzmaxinvoicingcommissionResponseCompound
     */
    objContactName:CustomContactNameResponse 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'

/**
 * @export 
 * A EzmaxinvoicingcommissionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingcommissionResponseCompound
 */
export class DataObjectEzmaxinvoicingcommissionResponseCompound {
    pkiEzmaxinvoicingcommissionID?:number = undefined
    fkiEzmaxinvoicingsummaryglobalID?:number = undefined
    fkiEzmaxpartnerID?:number = undefined
    fkiEzmaxrepresentativeID?:number = undefined
    dtEzmaxinvoicingcommissionStart:string = ''
    dtEzmaxinvoicingcommissionEnd:string = ''
    iEzmaxinvoicingcommissionDays:number = 0
    dEzmaxinvoicingcommissionAmount:string = ''
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
}

/**
 * @export 
 * A EzmaxinvoicingcommissionResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingcommissionResponseCompound
 */
export class ValidationObjectEzmaxinvoicingcommissionResponseCompound {
   pkiEzmaxinvoicingcommissionID = {
      type: 'integer',
      required: false
   }
   fkiEzmaxinvoicingsummaryglobalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxpartnerID = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   fkiEzmaxrepresentativeID = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   dtEzmaxinvoicingcommissionStart = {
      type: 'string',
      required: true
   }
   dtEzmaxinvoicingcommissionEnd = {
      type: 'string',
      required: true
   }
   iEzmaxinvoicingcommissionDays = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dEzmaxinvoicingcommissionAmount = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
} 


