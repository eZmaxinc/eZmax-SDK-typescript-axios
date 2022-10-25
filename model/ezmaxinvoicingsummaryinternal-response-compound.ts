/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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

import { DefaultObject } from '../base'

/**
 * @type EzmaxinvoicingsummaryinternalResponseCompound
 * A Ezmaxinvoicingsummaryinternal Object
 * @export
 */
export type EzmaxinvoicingsummaryinternalResponseCompound = EzmaxinvoicingsummaryinternalResponse & EzmaxinvoicingsummaryinternalResponseCompoundAllOf;


/**
 * @export 
 * A EzmaxinvoicingsummaryinternalResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzmaxinvoicingsummaryinternalResponseCompound
 */
export class DefaultObjectEzmaxinvoicingsummaryinternalResponseCompound extends DefaultObject {
   pkiEzmaxinvoicingsummaryinternalID?:number = undefined
   objEzmaxinvoicingsummaryinternalDescription:Partial<MultilingualEzmaxinvoicingsummaryinternalDescription> = {}
   sEzmaxinvoicingsummaryinternalDescriptionX:string = ''
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   a_objEzmaxinvoicingsummaryinternaldetail:Array<EzmaxinvoicingsummaryinternaldetailResponseCompound> = []
}


