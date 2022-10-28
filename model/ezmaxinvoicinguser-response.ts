/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicinguserVariationezsign } from './field-eezmaxinvoicinguser-variationezsign';

import { DefaultObject } from '../base'

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
    'pkiEzmaxinvoicinguserID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    'fkiBillingentityinternalID': number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicinguserResponse
     */
    'sBillingentityinternalDescriptionX': string;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    'fkiUserID': number;
    /**
     * The number of ezsign documents
     * @type {number}
     * @memberof EzmaxinvoicinguserResponse
     */
    'iEzmaxinvoicinguserEzsigndocument': number;
    /**
     * Whether there is an eZsign account
     * @type {boolean}
     * @memberof EzmaxinvoicinguserResponse
     */
    'bEzmaxinvoicinguserEzsignaccount': boolean;
    /**
     * Whether it is billable for eZsign
     * @type {boolean}
     * @memberof EzmaxinvoicinguserResponse
     */
    'bEzmaxinvoicinguserBillableezsign': boolean;
    /**
     * 
     * @type {FieldEEzmaxinvoicinguserVariationezsign}
     * @memberof EzmaxinvoicinguserResponse
     */
    'eEzmaxinvoicinguserVariationezsign': FieldEEzmaxinvoicinguserVariationezsign;
}
/**
 * A EzmaxinvoicinguserResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicinguserResponse
 */
export class DefaultObjectEzmaxinvoicinguserResponse extends DefaultObject {
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


