/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { DescriptionstaticResponse } from './descriptionstatic-response';

import { DefaultObject } from '../base'

/**
 * @type DescriptionstaticResponseCompound
 * A Descriptionstatic Object and children to create a complete structure
 * @export
 */
export type DescriptionstaticResponseCompound = DescriptionstaticResponse;


/**
 * @export 
 * A DescriptionstaticResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectDescriptionstaticResponseCompound
 */
export class DefaultObjectDescriptionstaticResponseCompound extends DefaultObject {
   pkiDescriptionstaticID:number = 0
   sDescriptionstaticDescription:string = ''
}


