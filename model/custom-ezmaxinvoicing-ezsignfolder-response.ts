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



/**
 * An EzmaxinvoicingEzsignfolder object containing information about the Ezmaxinvoicing for an Ezsignfolder
 * @export
 * @interface CustomEzmaxinvoicingEzsignfolderResponse
 */
export interface CustomEzmaxinvoicingEzsignfolderResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'fkiEzsignfolderID': number;*/
    'fkiEzsignfolderID': number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'fkiBillingentityinternalID'?: number;*/
    'fkiBillingentityinternalID'?: number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * Whether the TSA requirement is billable or not
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'bEzsigntsarequirementBillable': boolean;*/
    'bEzsigntsarequirementBillable': boolean;
    /**
     * Whether the MFA was used or not for the Ezsignfolder
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'bEzsignfolderMfaused': boolean;*/
    'bEzsignfolderMfaused': boolean;
    /**
     * Whether there was a signature is of type payment
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'bEzsignfolderPaymentused': boolean;*/
    'bEzsignfolderPaymentused': boolean;
    /**
     * Whether you have access to the Ezsignfolder or not
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponse
     */
    /*'bEzsignfolderAllowed': boolean;*/
    'bEzsignfolderAllowed': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzmaxinvoicingEzsignfolderResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzmaxinvoicingEzsignfolderResponse
 */
export class DataObjectCustomEzmaxinvoicingEzsignfolderResponse {
   fkiEzsignfolderID:number = 0
   fkiBillingentityinternalID?:number = undefined
   sEzsignfolderDescription:string = ''
   bEzsigntsarequirementBillable:boolean = false
   bEzsignfolderMfaused:boolean = false
   bEzsignfolderPaymentused:boolean = false
   bEzsignfolderAllowed:boolean = false
}

/**
 * @export 
 * A CustomEzmaxinvoicingEzsignfolderResponse Validation Object
 * @class ValidationObjectCustomEzmaxinvoicingEzsignfolderResponse
 */
export class ValidationObjectCustomEzmaxinvoicingEzsignfolderResponse {
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   bEzsigntsarequirementBillable = {
      type: 'boolean',
      required: true
   }
   bEzsignfolderMfaused = {
      type: 'boolean',
      required: true
   }
   bEzsignfolderPaymentused = {
      type: 'boolean',
      required: true
   }
   bEzsignfolderAllowed = {
      type: 'boolean',
      required: true
   }
} 


