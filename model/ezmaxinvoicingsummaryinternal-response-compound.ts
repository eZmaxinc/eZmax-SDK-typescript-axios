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
import { EzmaxinvoicingsummaryinternalResponse } from './ezmaxinvoicingsummaryinternal-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryinternalResponseCompoundAllOf } from './ezmaxinvoicingsummaryinternal-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryinternaldetailResponseCompound } from './ezmaxinvoicingsummaryinternaldetail-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualEzmaxinvoicingsummaryinternalDescription } from './multilingual-ezmaxinvoicingsummaryinternal-description';

/**
 * @type EzmaxinvoicingsummaryinternalResponseCompound
 * A Ezmaxinvoicingsummaryinternal Object
 * @export
 */
export type EzmaxinvoicingsummaryinternalResponseCompound = EzmaxinvoicingsummaryinternalResponse & EzmaxinvoicingsummaryinternalResponseCompoundAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription } from './'

/**
 * @export 
 * A EzmaxinvoicingsummaryinternalResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryinternalResponseCompound
 */
export class DataObjectEzmaxinvoicingsummaryinternalResponseCompound {
    pkiEzmaxinvoicingsummaryinternalID?:number = undefined
    objEzmaxinvoicingsummaryinternalDescription:MultilingualEzmaxinvoicingsummaryinternalDescription = new DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription()
    sEzmaxinvoicingsummaryinternalDescriptionX:string = ''
    fkiEzmaxinvoicingID?:number = undefined
    fkiBillingentityinternalID:number = 0
    sBillingentityinternalDescriptionX:string = ''
    a_objEzmaxinvoicingsummaryinternaldetail:Array<EzmaxinvoicingsummaryinternaldetailResponseCompound> = []
}

/**
 * @export 
 * A EzmaxinvoicingsummaryinternalResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryinternalResponseCompound
 */
export class ValidationObjectEzmaxinvoicingsummaryinternalResponseCompound {
   pkiEzmaxinvoicingsummaryinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objEzmaxinvoicingsummaryinternalDescription = new ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription()
   sEzmaxinvoicingsummaryinternalDescriptionX = {
      type: 'string',
      required: true
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
   a_objEzmaxinvoicingsummaryinternaldetail = {
      type: 'array',
      required: true
   }
} 


