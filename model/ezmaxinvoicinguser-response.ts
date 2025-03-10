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
import type { FieldEEzmaxinvoicinguserVariationezsign } from './field-eezmaxinvoicinguser-variationezsign';

/**
 * A Ezmaxinvoicinguser Object
 * @export
 * @interface EzmaxinvoicinguserResponse
 */
export interface EzmaxinvoicinguserResponse {
    /**
     * The unique ID of the Ezmaxinvoicinguser
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'pkiEzmaxinvoicinguserID'?: number;*/
    'pkiEzmaxinvoicinguserID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'fkiEzmaxinvoicingID'?: number;*/
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'fkiBillingentityinternalID': number;*/
    'fkiBillingentityinternalID': number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'sBillingentityinternalDescriptionX': string;*/
    'sBillingentityinternalDescriptionX': string;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'fkiUserID': number;*/
    'fkiUserID': number;
    /**
     * The number of ezsign documents
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'iEzmaxinvoicinguserEzsigndocument': number;*/
    'iEzmaxinvoicinguserEzsigndocument': number;
    /**
     * Whether there is an eZsign account
     * @type {boolean}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'bEzmaxinvoicinguserEzsignaccount': boolean;*/
    'bEzmaxinvoicinguserEzsignaccount': boolean;
    /**
     * Whether it is billable for eZsign
     * @type {boolean}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'bEzmaxinvoicinguserBillableezsign': boolean;*/
    'bEzmaxinvoicinguserBillableezsign': boolean;
    /**
     * 
     * @type {FieldEEzmaxinvoicinguserVariationezsign}
     * @memberof EzmaxinvoicinguserResponse
     */
    /*'eEzmaxinvoicinguserVariationezsign': FieldEEzmaxinvoicinguserVariationezsign;*/
    'eEzmaxinvoicinguserVariationezsign': FieldEEzmaxinvoicinguserVariationezsign;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicinguserResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicinguserResponse
 */
export class DataObjectEzmaxinvoicinguserResponse {
   pkiEzmaxinvoicinguserID?:number = undefined
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   fkiUserID:number = 0
   iEzmaxinvoicinguserEzsigndocument:number = 0
   bEzmaxinvoicinguserEzsignaccount:boolean = false
   bEzmaxinvoicinguserBillableezsign:boolean = false
   eEzmaxinvoicinguserVariationezsign:FieldEEzmaxinvoicinguserVariationezsign = 'Charge'
}

/**
 * @export 
 * A EzmaxinvoicinguserResponse Validation Object
 * @class ValidationObjectEzmaxinvoicinguserResponse
 */
export class ValidationObjectEzmaxinvoicinguserResponse {
   pkiEzmaxinvoicinguserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicinguserEzsigndocument = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzmaxinvoicinguserEzsignaccount = {
      type: 'boolean',
      required: true
   }
   bEzmaxinvoicinguserBillableezsign = {
      type: 'boolean',
      required: true
   }
   eEzmaxinvoicinguserVariationezsign = {
      type: 'enum',
      allowableValues: ['Charge','Refund','Same'],
      required: true
   }
} 


