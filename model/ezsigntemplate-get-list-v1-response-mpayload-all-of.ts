/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateListElement } from './ezsigntemplate-list-element';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplateGetListV1ResponseMPayloadAllOf
 */
export interface EzsigntemplateGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<EzsigntemplateListElement>}
     * @memberof EzsigntemplateGetListV1ResponseMPayloadAllOf
     */
    'a_objEzsigntemplate': Array<EzsigntemplateListElement>;
}
/**
 * A EzsigntemplateGetListV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateGetListV1ResponseMPayloadAllOf
 */
export class DefaultObjectEzsigntemplateGetListV1ResponseMPayloadAllOf extends DefaultObject {
   a_objEzsigntemplate:Array<EzsigntemplateListElement> = []
}


