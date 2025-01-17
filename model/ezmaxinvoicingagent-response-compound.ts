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
import type { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzmaxinvoicingagentResponse } from './ezmaxinvoicingagent-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzmaxinvoicingagentVariationezmax } from './field-eezmaxinvoicingagent-variationezmax';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzmaxinvoicingagentVariationezsign } from './field-eezmaxinvoicingagent-variationezsign';

/**
 * @type EzmaxinvoicingagentResponseCompound
 * A Ezmaxinvoicingagent Object
 * @export
 */
/*export type EzmaxinvoicingagentResponseCompound = EzmaxinvoicingagentResponse;*/
export interface EzmaxinvoicingagentResponseCompound {
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzmaxinvoicingagentResponseCompound
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
 * A EzmaxinvoicingagentResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingagentResponseCompound
 */
export class DataObjectEzmaxinvoicingagentResponseCompound {
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
}

/**
 * @export 
 * A EzmaxinvoicingagentResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingagentResponseCompound
 */
export class ValidationObjectEzmaxinvoicingagentResponseCompound {
   objContactName = new ValidationObjectCustomContactNameResponse()
} 


